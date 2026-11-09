# R67 — Current/Original WFP AppId scope mismatch under pre-proxied connections

2026-11-09. ONLY i-shutov/flowbridge / research/windows-wfp-ale-attribution-20261107. Independent architecture R&D; not beta, PR #56, PacketBound/G2 or release proof.

**Exact baseline:** research c6720086f079d3df5d63eae9a8d4f376506333bb; main 5b5afc2feeda2195f302380e615ba003d4906e09. No driver, callout, filter, BFE, network, service, runner, firewall, UFW, Defender, SecureBoot or automation mutation.

## Concrete code discrepancy (not merely a proposed architecture)

- policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602, function conditions(): the CONNECT_REDIRECT filter uses FWPM_CONDITION_ALE_APP_ID; the AUTH_CONNECT filter uses FWPM_CONDITION_ALE_ORIGINAL_APP_ID.
- redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6: classify() reads FWPS_FIELD_ALE_CONNECT_REDIRECT_V4/V6_ALE_APP_ID; auth_check() reads the distinct FWPS_FIELD_ALE_AUTH_CONNECT_V4/V6_ALE_ORIGINAL_APP_ID.
- Microsoft documents ALE_ORIGINAL_APP_ID in **both** CONNECT_REDIRECT and AUTH_CONNECT for IPv4 and IPv6 (Windows 8+). It means the original app path for already-proxied connections, while ALE_APP_ID is the currently associated app. Thus *not* a missing kernel field.

**Counterexample scope:** selected original application A, but a pre-existing independent proxy B makes the current AppId B. With original=A/current=B, the present CONNECT_REDIRECT filter (current=A) does not select this classification; the AUTH_CONNECT original=A filter may select it. If AUTH callback is delivered without a valid FlowBridge receipt, the code requests BLOCK. Without callback it is UNOBSERVED. This is a *foreign-proxy chain compatibility/coverage mismatch*, NOT proven DIRECT leakage, bypass, physical block, or Windows reproduction.

Changing only the redirect filter to ORIGINAL_APP_ID is NOT authorized as a fix: classify() still rejects different current AppId; metadata.processId and process epoch at a proxied callback cannot automatically be equated to historical original A. Doing so could misattribute proxy B's process. Windows has not documented here the mandatory original EPROCESS reference or cross-callback classify ticket. No production code changed.

## Executable clean-room counterexample

The accompanying r67_independent.mjs is a deterministic Node bitmask oracle, no network or Windows calls. A separately implemented Python tuple oracle (6/6 tests PASS) and Node were run independently on 16,384 cases (IPv4/IPv6, TCP/UDP, all 4096 Boolean states per family and protocol). All counters agree and full ordered decision-stream SHA-256 matches: 525e833279b0543c4450eb29e257b3f68d328c06e45d13673c105572cc4796e6.

Counts: 2,048 selected-ORIGINAL/foreign-CURRENT TCP states miss the current redirect filter; 2,040 conditional model BLOCK_REQUESTED, 2,048 AUTH_UNOBSERVED, 4,096 outside AUTH filter, 8 hypothetical MODEL_PERMIT_ONLY; among those eight, 4 have physically dead original owner and 4 may have sibling DIRECT in hidden test-world truth. 8,192 UDP scenarios are out of this TCP scope. These are *model* results, not actual WFP dispatch or packets. BLOCK_REQUESTED is NOT confirmation of packet suppression. Process exit/PID reuse, repeated 5-tuple, original destination, redirect records, SSH/WFP loss and callback-lifetime still lack native trust proof.

Pure Rust offline no-unsafe diagnostic model and Python reference oracle/test logs are in the R67 checkpoint. Rust compilation was **not performed** (no rustc/cargo toolchain). The Rust type refuses to assert original_owner_proven/no_direct_proven even in the hypothetical success model.

## Trust boundary / decision

Narrow GO: Windows field/condition for original AppId exists on both relevant layers/families, and source-policy mismatch is real. NO-GO: original AppId as process PID+creation epoch+canonical executable, authenticated redirected accepted socket, one-use kernel origin CLAIM, death/reauthorization, sibling DIRECT, DNS/UDP/QUIC, physical egress and leak-free. Keep R65 unverified FFI allocator path quarantined.

**Next decisive R68:** dual-axis (current app vs original app) *offline* policy design: for current=A vs original=A, define separate original-owner proof obligations; research documented meaning of FWPS_INCOMING_METADATA_VALUES0.processId, transportEndpointHandle, originalDestination and redirectRecords on AUTH_CONNECT for a previously proxied flow. Require kernel-bound original EPROCESS identity; if docs do not guarantee it, NO-GO. No WFP activation without separate owner rescue/rollback gates.

Microsoft references:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_connect_redirect_v4
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_connect_redirect_v6
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_auth_connect_v4
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_auth_connect_v6
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
