# R52 — conditional FWP_EMPTY BFE prefilter blind spot during ALE reauthorization

2026-11-08. Independent source-only WFP/ALE research **only** in `research/windows-wfp-ale-attribution-20261107`. Not beta, PR #56, driver test, PacketBound/G2, historical G1, or no-DIRECT/leak-free proof. No driver/callout/filter installation, networking, VNC, runner, services, firewall, security configurations or automations touched.

## Pinned repository state and source
Parent research HEAD: `6a10d4d358f2aa3f487d86a26f773b0475154c09`; main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
- `research/wfp-ale/kernel-r19/policy_windows.rs` blob `acf60334320d970f58af3349ee75fbaa59826602`: `conditions()` registers *two* exact AUTH filter predicates: selected `FWPM_CONDITION_ALE_ORIGINAL_APP_ID` `FWP_BYTE_BLOB_TYPE` and `FWPM_CONDITION_IP_PROTOCOL` TCP (6), both `FWP_MATCH_EQUAL`. Filter action: `FWP_ACTION_CALLOUT_TERMINATING`.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: `auth_check` requires many WFP metadata fields and BLOCKs every `IS_REAUTHORIZE`; `auth_classify` only executes if BFE dispatches it.
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs` blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`: AUTH callout invokes `redirect::auth_classify`; no pending-op identity path.

## New independent dispatch boundary
Microsoft documents that a callout is invoked only when **all** filter conditions match. During ALE reauthorization **some** classifiable fields may be `FWP_EMPTY`; `FWP_EMPTY` may be matched explicitly using `FWP_MATCH_EQUAL`. However, the existing selected-AppId/TCP equalities are NOT `FWP_EMPTY` conditions. Therefore if a required field is empty, the two-condition filter cannot be treated as proof that our callback necessarily runs. The BLOCK inside `auth_check` is not a global OS denial.

**Critical limitation:** the official general documentation does not establish that `ALE_ORIGINAL_APP_ID` or TCP protocol is actually empty on the target reauthorization sequence. The scenario is conditional; no physical bypass has been witnessed. A permissive *other filter* is a separate model assumption, not evidence of real BFE policy.

`FWPS_FIELD_ALE_AUTH_CONNECT_V4/V6_REAUTHORIZE_REASON` and `FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION` distinguish **cause**, not a specific issuance. `FWPS_INCOMING_METADATA_VALUES0` members are valid only under corresponding `currentMetadataValues` bits: `FWPS_METADATA_FIELD_COMPLETION_HANDLE`, `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`. `FwpsPendOperation0` uses the initial completionHandle, returns an opaque completionContext for `FwpsCompleteOperation0`, and completion initiates a reauthorization. This does NOT document a returned unique ticket in the new classify. Reauthorization cannot simply be pended a second time.

## Executed deterministic independent negative tests
- Python stdlib model: **17/17 PASS**, tested in local isolated user mode; no native Windows execution.
- Independent Node model (published at `research/wfp-ale/r52/r52_independent_oracle.mjs`): **1,728 states**, exact agreement on all counters:
  - callback invoked: **192**; not invoked: **1,536**.
  - hypothetical initial AUTH accepted: **4** (assumed source/epoch/ticket/SSH guards).
  - selected REAUTHORIZE missed by this filter with an unknown field and **assumed** fallback PERMIT: **160**.
  - among those with assumed dead owner or SSH failure: **120** (60 IPv4, 60 IPv6).
  - **8 indistinguishable observed pairs**: selected and sibling source differ only in original identity that is unavailable in the observation. No deterministic policy using *only those observed fields* can simultaneously deny selected and allow sibling. This is a conditional information limit, not a Windows measurement.
- Four mutated filter witness cases show that removing either equality changes the dispatch set. Rust toolchain not installed; permitted independent Python/Node negative proof was chosen instead.

## Trust chain and decision
To reach native GO, prove the same kernel-origin identity (PID + process object/creation epoch/start key + canonical EXE/WFP AppId), original target, and exact issuance at `ALE_CONNECT_REDIRECT_V4/V6`; prove the *selected reauthorization is routed to a filter* even with unknown classifiable fields; bind initial `AUTH_CONNECT` `completionHandle` and `completionContext` to exactly the new `CLASSIFY_COMPLETION` classify without tuple/PID guesses. Then independently verify accepted-socket WFP context/records via `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS`, outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, authenticated SSH handoff, owner exit/PID/tuple reuse, sibling DIRECT, DNS/UDP/QUIC, dual-stack and WFP/SSH loss.

**GO** for documented BFE prefilter visibility as its own proof obligation and for deterministic counterexamples to unconditional callback execution. **NO-GO** for actual missing `ORIGINAL_APP_ID`, real traffic escape, exact pending-operation identity, owner-liveness, system no-DIRECT, PacketBound/G2 and leak-free.

**Next decisive safe experiment:** source-only check if documented per-flow, authenticated reauthorization routing exists independent of potentially `FWP_EMPTY` AppId/protocol and test the collateral sibling false-block risk from a catch-all `FWP_EMPTY` filter. Do not activate native WFP, driver, runner or network.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
