# R53 — BFE reauthorization: wildcard visibility versus sibling/UDP provenance

2026-11-08. Scope **only** `research/windows-wfp-ale-attribution-20261107` in `i-shutov/flowbridge`. Independent read-only research, not beta, PR #56, driver activation, PacketBound/G2 PASS, no-DIRECT or leak-free.

## Pinned source

Parent research HEAD `e836398ff7efe724653a1de31dc03e9d22dbece3`, tree `480d78dee9dd8d4ede65e02cfa2b000e2a79165d`; main `5b5afc2feeda2195f302380e615ba003d4906e09`.

- `research/wfp-ale/kernel-r19/policy_windows.rs`, blob `acf60334320d970f58af3349ee75fbaa59826602`: selected `FWPM_CONDITION_ALE_ORIGINAL_APP_ID` AND TCP `FWPM_CONDITION_IP_PROTOCOL` both `FWP_MATCH_EQUAL`, shared sublayer weight `0x7000`, auto-assigned `FWP_EMPTY` filter weights, terminating AUTH callout.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`, blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: `auth_check` denies all `IS_REAUTHORIZE`; the check runs only after BFE dispatch. Missing process/endpoint/original-destination evidence denies a received classification.
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs`, blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`: AUTH callback forwards to `redirect::auth_classify`. No actual WFP operations were performed.

## Documented filter arbitration and empty fields

Microsoft *Processing Classify Callouts* says all conditions must match to dispatch, and a zero-condition filter matches all layer classifications. A dedicated sublayer with one all-traffic matching filter is the documented way to ensure **layer visibility**, but never to prove originating process or ticket.

Microsoft *ALE Reauthorization* permits `FWP_EMPTY` on some fields, can classify packets in either direction, and permits explicit `FWP_MATCH_EQUAL` on `FWP_EMPTY`. Neither Microsoft nor this experiment establishes that `ALE_ORIGINAL_APP_ID` or `IP_PROTOCOL` is empty on a **real** FlowBridge reauthorization. All empty-field cases below are conditional hypotheses.

Within a sublayer, the highest-weight matching terminating filter skips remaining filters. In the source, `FWP_EMPTY` is also used as an auto-assigned **filter weight** (a different use from missing classifiable data). Merely adding a catch-all to the same sublayer does not guarantee that *that* callback sees a selected flow when another terminating filter wins. A singleton wildcard in its separate sublayer would widen observation **conditional on correctly installed native policy**; native installation is prohibited here.

## Executed deterministic negative experiment

Independent Python stdlib model: **20/20 PASS**. Independently authored Node oracle (committed next to this report) enumerates the same **1,536** synthetic cases with exact agreement. Dimensions: IPv4/v6, actual selected/sibling process, actual TCP/UDP, AppId present/EMPTY, protocol present/EMPTY, classify-completion/policy-change reason, missing/valid/foreign hypothetical receipt, alive/dead owner, SSH healthy/lost and valid/invalid session.

| Hypothetical AUTH filter dispatch | All modeled events | Selected TCP (of 384) | Incidental sibling TCP | Incidental UDP |
| --- | ---: | ---: | ---: | ---: |
| Current selected AppId AND TCP | 96 | 96 | 0 | 0 |
| Selected/EMPTY AppId AND TCP/EMPTY protocol (multiple OR filters) | 864 | 384 | 192 | 288 |
| No-condition singleton sublayer | 1536 | 384 | 384 | 768 |

The strict hypothetical *decision* oracle gives 16 conditional permits, 912 denials, 608 outside-scope decisions. All 16 permits **assume** an independently authenticated, same-flow receipt binding original owner AND protocol plus live owner, live SSH, current epoch/session. FlowBridge has **not** established such a receipt on pending/policy reauthorization. A naive permit-on-unknown decision would admit 32 modeled selected-TCP cases with already dead owner. In the strict model 64 sibling-TCP and 96 UDP cases without a receipt are denied, illustrating possible collateral blocking.

Proved by finite observation comparison, **conditioned on missing fields**: 64 indistinguishable selected-vs-sibling TCP pairs with absent original AppId, and 32 indistinguishable selected-TCP-vs-selected-UDP pairs with absent protocol. Since WFP cause, other observed fields, and missing receipt coincide, no deterministic action using only those observations can both deny unauthorized selected TCP and admit every sibling/UDP case. This is not a real Windows emission count or physical leak.

The Python negative suite checks both families, missing and foreign receipt, process death, bad session, SSH loss, TCP/UDP, sibling isolation, unknown fields and auto-weight callback-order ambiguity. Node cross-verifies all counts. Rust not compiled and no Rust passing-test claim is made.

## Trust chain, NO-GO and next step

Real proof still requires same kernel-origin WFP `ALE_CONNECT_REDIRECT_V4/V6` AppId and original target bound to referenced process+creation epoch/start key+canonical EXE at allowed IRQL; native `ALE_AUTH_CONNECT_V4/V6` receipt and exact per-issuance `PEND -> COMPLETE -> REAUTHORIZE` binding not inferred from PID, 5-tuple or reason; accepted-socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS)`, outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, single claim and trusted SSH; IPv4/v6, PID reuse, owner exit, sibling DIRECT, DNS/UDP/QUIC and WFP/SSH loss. No full-source proof, driver load or physical egress test exists.

**Conditional GO** only for the documented concept of a singleton no-condition sublayer providing layer-level callback visibility. **NO-GO** for owner attribution, liveness and collateral-free scope when essential fields are absent. Do not deploy a broad blocking filter or infer G2/PacketBound/no-DIRECT. Dynamic session is not persistent kill switch; historical G1 `dd1ab3c` not transferred.

**R54 decisive safe experiment:** source/spec-only study of `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`, `FWPS_METADATA_FIELD_FLOW_HANDLE`, endpoint/flow lifetime and a native binding across completion and policy reauthorization. Test whether an independently verifiable identity exists without tuple/PID joins. No drivers, filters, VNC, runner, services, network, firewall, protections, signed-driver work or paid actions; do not touch main/release, integration beta, PR #56, automation or other repositories.

## Official Windows API references

- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
