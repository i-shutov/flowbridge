# FlowBridge R151 — endpoint identity regression in R150 selected-only candidate

Date: 2026-11-13. **Only** `research/windows-wfp-ale-attribution-20261107`. Initial research HEAD `2675c04eab24ccc6ba1e66e282b9c5b2234fcae9`; main `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Significant finding — model-specific, NOT native WFP evidence

The proposed R150 `Candidate.issue()` creates distinct tickets without checking whether an endpoint was already issued, and does not reject endpoint 0. Its `claim()` rejects *ticket* replay but can return `MODEL_ROUTE` for two tickets referring to **the same PID/epoch/start-key/process reference/endpoint and 5-tuple**. Thus R150's owner-churn improvement cannot be transplanted into the R19 route as a complete safety contract.

The existing R19 `handoff.rs::Book::issue()` *does* forbid endpoint 0 and duplicate endpoint issuance via non-evicting tombstones. Simply copying that mechanism reproduces the 4096-endpoint availability blocker identified in R148. A replacement must satisfy both invariants: no false re-authentication of a reused endpoint and bounded long-lived operation. Neither is solved here. The observation is about the **test model**, not an actual Windows connection, DIRECT bypass or kernel implementation defect.

## Executed reproducible negative tests

`r151_negative.py` imports the **actual R150 Candidate** (pinned by Git blob SHA) and calls real `configure`, `birth`, `issue`, `claim` and `death` methods. An independently written Node `r151_oracle.mjs` implements the second oracle. Normal Python and `python -O` agree with Node on 64 deterministic trace results:

- 48 alias cases: two different one-shot tickets both claim `MODEL_ROUTE` for the *same* endpoint (same/different synthetic tuple; v4/v6, two PIDs). Replay of an already claimed ticket is rejected.
- 2 zero-endpoint/empty-tuple cases: `MODEL_ROUTE` despite R19 rejecting endpoint 0.
- 12 matched process-exit/PID+epoch-reuse cases: old ticket rejected, new ticket accepted; actual endpoint lifetime proof absent.
- 2 distinct-endpoint positive controls.

Trace SHA-256: `9f9be61abb1ccd080a30f5da3f3fe56ed1eb5e4482ea22cbe544cfec800a89a9`. Python and independent Node had **zero disagreements**. The negative source-mutation test (added newline to R150 source) failed the exact pin check under `-O`. Native Rust, Windows and WFP were **not** executed.

File pins (verified against the exact GitHub revision):
- `r150/r150_preselection_negative.py` — `3e81d27a80e88671775be9015f436bdf5cd100bb`;
- `kernel-r19/kernel/src/handoff.rs` — `e1d17217db50362ba9c4efc83af820b6beb094cf`;
- `kernel-r19/kernel/src/redirect.rs` — `a093f049d162987981a957aac90db1014bc6ff09`.

The full R150 candidate bytes were verified locally using the previous checkpoint archive. Exact R19 source was verified through GitHub, **not locally**. Hence the run used `--model-only`; source-pinned local execution remains pending.

## Platform boundary and next decisive experiment

Microsoft documents `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE` in `FWPS_INCOMING_METADATA_VALUES0`, and `FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6` / `FWPS_LAYER_ALE_RESOURCE_RELEASE_V4/V6` as endpoint-lifetime signals. These facts do *not* independently prove an unbounded never-reused numeric handle, native connection issuance nonce shared between CONNECT_REDIRECT and AUTH_CONNECT, or the order of delayed AUTH versus closure on FlowBridge's target Windows build.

- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

A viable future Rust user-mode transition model must separately retain broker and selected-process birth provenance and reject ABA: same numeric endpoint after closure, delayed AUTH, PID/epoch reuse, repeated 5-tuple, v4/v6 compartment changes. Only explicitly witnessed native issuance/closure ordering may justify recycling tombstones. First reproduce these tests with the **full source pin**; then native kernel lab requires independent owner authorization and driver/VNC/SYSTEM rescue/rollback gates.

Full unproven trust chain: referenced `PEPROCESS` + FileObject + creation epoch/start key + canonical executable/WFP AppId → actual `ALE_CONNECT_REDIRECT_V4/V6` / `ALE_AUTH_CONNECT_V4/V6` and `FWPS_CONNECT_REQUEST0` → WFP redirect context/records queried on the *real accepted socket* → one-shot CLAIM → `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` on physical SSH socket before connect → independently enforced no-DIRECT including DNS/UDP, sibling, reauthorization, BFE/SSH loss and IPv4/IPv6. No correlation by late PID or 5-tuple can replace that chain.

**Architecture NO-GO, not PacketBound/G2 PASS or leak-free.** No kernel driver/callout/filter, NDISRD, WFP policy, networking, services, firewall, Defender, SecureBoot, MemoryIntegrity, runner, automation, beta, PR #56 or main/release was modified.
