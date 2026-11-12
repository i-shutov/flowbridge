# FlowBridge R147 — conditional ALE reauthorization filter non-match / callback reachability

Date: 2026-11-12. **Research-only** `research/windows-wfp-ale-attribution-20261107`.
Pinned analysis input HEAD: `ce046f20289da250c7eccde7410e5d216219b1ff` (R146), `main` at preflight: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## New, bounded architectural counterexample

R146 checks what `auth_check()` does **if** R19 AUTH_CONNECT classifies the flow. It does *not* prove that the exact selected `ALE_ORIGINAL_APP_ID` filter matched the flow. The R19 dynamic policy creates `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` filters with the conjunction:

- `FWPM_CONDITION_ALE_ORIGINAL_APP_ID`, `FWP_MATCH_EQUAL`, `FWP_BYTE_BLOB_TYPE`, a pinned application ID; **and**
- `FWPM_CONDITION_IP_PROTOCOL`, `FWP_MATCH_EQUAL`, TCP=6.

With **hypothetical** `FWP_EMPTY` or missing original-AppId at an AUTH reauthorization, or a mismatching AppId, the exact pinned BLOB condition does not establish a match. A filter which is not selected cannot invoke its `auth_callback`; the callback's fail-closed implementation therefore cannot be cited as proof of enforcement for that packet. Even when both conditions match, same-sublayer earlier terminating filters can make callback arrival uncertain. Conversely, an absent filter cannot enforce by that filter. These are **coverage counterexamples** to an inference from callback logic to end-to-end enforcement, **not** native DIRECT or leak evidence.

Microsoft explicitly states that on ALE reauthorization **some** classifiable fields may be `FWP_EMPTY`, but does **not** establish that `ALE_ORIGINAL_APP_ID` becomes `FWP_EMPTY` on any specific Windows build or FlowBridge path. We do not assert that it does. The decision to block a flow with missing original AppId **cannot** be established by this appId-specific filter alone; independent native filter-matching/coverage proof is required. Existing other WFP filters/firewall policy could still block the packet; no ALLOW or leak is inferred.

Relevant authoritative docs:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_data_type
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

Source pins verified via exact GitHub repository revision:
- `research/wfp-ale/kernel-r19/policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602`;
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: `a093f049d162987981a957aac90db1014bc6ff09`.

## Reproducible negative tests (clean-room/offline)

At the **exact** research checkout:

```sh
python -B research/wfp-ale/r147/r147_filter_coverage_negative.py
python -O -B research/wfp-ale/r147/r147_filter_coverage_negative.py
node research/wfp-ale/r147/r147_independent_oracle.mjs
```

When code is **not** locally checked out, a strictly weaker model-only run can use `--model-only`; it must never be described as source-pinned local or kernel execution.

The independent Python and Node implementations enumerate 256 synthetic cases: IPv4/IPv6, BLOB selected vs EMPTY/foreign/absent AppId, TCP vs UDP, initial vs reauthorization, filter absent/present, selected-process live/dead, and earlier same-sublayer terminating decision present/absent. Results are purely categorical (no ACCEPT/BLOCK packet verdicts):

- `FILTER_ABSENT_NO_CLAIM`: 128;
- `FILTER_NONMATCH_NO_CALLBACK`: 112;
- `FILTER_MATCH_MAY_BE_SKIPPED`: 8;
- `FILTER_ELIGIBLE_NOT_KERNEL_PROOF`: 8.

Four synthetic *reauth + FWP_EMPTY + selected process live + TCP + installed filter* cases are non-matches. Source-backed input pin verification: 2/2 blobs and all seven source markers checked independently using the GitHub connector. Both local offline oracles yielded exactly the same 256-row SHA-256 matrix:

`0310f8a48b54cc0225940da80a7f4fa893c70903090cf879d5bdc06975eac72c`

No native WFP classify, Windows host, driver, callout, filter creation/registration, network connection, or packet capture was executed. Model variables are explicitly **assumptions**, not witnessed Windows facts. No claim of `PacketBound/G2 PASS`, no-DIRECT, leak-free or historical G1 acceptance.

## Trust-chain impact and next decisive experiment

Kernel process creation `PS_CREATE_NOTIFY_INFO` / referenced `PEPROCESS` + FileObject / `PsGetProcessStartKey` / `PsGetProcessCreateTimeQuadPart` -> original/current ALE AppId and actual filter hit at `ALE_AUTH_CONNECT_V4/V6` / `FWPS_METADATA_FIELD_PROCESS_ID`, endpoint, flags -> `FWPS_CONNECT_REQUEST0` redirection and opaque WFP records/context -> exact accepted socket -> one-shot CLAIM -> physical `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` SSH socket -> independent direct-egress packet proof. A late PID or reused 5-tuple cannot prove this chain. All kernel-origin, process-lifetime, IPv4/IPv6 compartment, sibling DIRECT, DNS/UDP/QUIC, SSH/BFE-loss, and reauthorization gates remain NO-GO.

Next **permitted** step: source-pin gate on exact checkout and inspect static `FWPM_FILTER0` readback in the already approved *read-only* Windows inventory, without installing policy; readback is insufficient to show callback reachability. A **decisive** trace of `ALE_ORIGINAL_APP_ID` field presence/type, filter hit, rights, flag/phase, and actual verdict for the *same* reauthorized flow requires separately authorized kernel lab and complete VM/rescue/rollback gates. Do not alter any service, WFP object, driver, network, protection setting, runner, main, beta, PR #56, automation, or another repository.
