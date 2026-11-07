# FlowBridge WFP/ALE — independent research checkpoint R1

Date: 2026-11-07. Base: main `5b5afc2feeda2195f302380e615ba003d4906e09`.
Branch: `research/windows-wfp-ale-attribution-20261107`, and NO other branch.
Status: architecture **NO-GO for release**; only read-only research and pure Rust trust-model tests.
Not beta, not PR #56, not G2/PacketBound PASS, not a native redirect demonstration.

## Central distinction: connection-level proof, not packet heuristics

NDISRD packet bytes, ETW connection events, IP Helper tables and user-mode 5-tuples cannot be equated into an authenticated packet owner by matching timestamps, PID, ISN, sequence, hash or destination. WFP ALE_CONNECT_REDIRECT is the relevant alternative architecture: a native kernel classify callout can see the connection request and WFP-supplied application identity, redirect it, and attach a connection-specific context. The proxy must retrieve redirect records/context **from the actual redirected accepted socket** and set the records on each outbound socket before connect. This is a conditional design, not a currently proven FlowBridge connection chain.

The WFP kernel callout is **not optional** for this transparent redirect design. Read-only BFE filter enumeration, user-mode ETW or GetExtendedTcpTable cannot replace the callout or prove that a specific connection was intercepted.

## Required documented API and trust boundary

| Step | Official platform API | Required proof | Current |
| --- | --- | --- | --- |
| Selected executable | `FwpmGetAppIdFromFileName0`, `FWPM_CONDITION_ALE_APP_ID` | Exact opaque full WFP AppId, not basename; two same-name EXEs must be distinguished | NO-GO |
| Native classify | `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_FIELD_ALE_CONNECT_REDIRECT_*_ALE_APP_ID`, `FWPS_METADATA_FIELD_PROCESS_ID` when valid | Owner and target from the same kernel classify, not after-the-fact PID lookup | NO-GO |
| Process epoch | `PsLookupProcessByProcessId` → referenced `EPROCESS` → `PsGetProcessCreateTimeQuadPart` | Creation time of that process; handle and event lifetime, IRQL, exit/reuse races proved | NO-GO |
| Redirect | `FwpsAcquireWritableLayerDataPointer0`, `FWPS_CONNECT_REQUEST0`, `FwpsApplyModifiedLayerData0`, `FwpsRedirectHandleCreate0` | Original v4/v6 destination, localRedirectTargetPID, owned redirect handle and context preserved | NO-GO |
| Multiple inspectors | `FwpsQueryConnectionRedirectState0`, `FWPS_CONNECT_REQUEST0.previousVersion` | No self/previous-self loop, documented other-inspector coexistence | NO-GO |
| Accept | `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)` and `..._CONTEXT` | Read on the actual accepted socket, bound to service session, classified owner, ticket and original target | NO-GO |
| Outbound proxy socket | `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` | Forward opaque WFP record before outbound connect, including retries; no silent fallback | NO-GO |
| Selected-app deny | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` | Independently enforced denial for selected sibling DIRECT when SSH/WFP/proxy fails | NO-GO |
| Network coverage | ALE_AUTH_CONNECT TCP/UDP semantics and per-family native traffic tests | TCP IPv4/IPv6; separate DNS, UDP/QUIC and OS resolver analysis | NO-GO |

### Three traps that invalidate an apparently successful attribution test

**1. PID + creation epoch are not a retrospective join.** Windows user-mode `OpenProcess`, `GetProcessTimes` and `QueryFullProcessImageNameW` describe the opened process, not necessarily the historical owner of a TCP connection. A re-used PID may refer to a different process. `PsLookupProcessByProcessId` can return a referenced process object, and `PsGetProcessCreateTimeQuadPart` returns its creation time; however, `PsLookupProcessByProcessId` is **pageable and requires IRQL <= APC_LEVEL**. It cannot be assumed legal in an arbitrary WFP classify context. An authorized future adapter must prove the provenance and safe acquisition at the event boundary; unavailable epoch means NO-GO, not speculative enrichment by ETW.

**2. Redirect records are socket-bound, not an arbitrary security token.** The WFP redirect record is an opaque Windows buffer, not a client-provided signed proof. No flow is trusted because some process provided a plausible record ID, port, hash or boolean. Any eventually accepted source must be the owned OS socket and its WFP query result. In this repo, the Rust model consumes *assumed* evidence only; it cannot itself authenticate a callout.

**3. Fail closed inside a proxy is not an OS kill switch.** A service may reject an accepted TCP stream when SSH goes down, but an unrelated/direct socket does not enter that service. Dynamic WFP filter removal on crash may restore DIRECT routing; its safety cannot be inferred from service-side error paths. A genuine persistent system-level no-DIRECT gate is separate and currently unauthorized. A same-basename sibling is intentionally outside selected-app scope, not a leak-proof success.

### Additional boundaries

- `FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF` must not be redirected again. `FWPS_CONNECTION_REDIRECTED_BY_OTHER` requires a separately justified interoperability decision.
- `FWPS_FIELD_ALE_*_ALE_ORIGINAL_APP_ID` can preserve original application identity through a proxy chain, but does not alone authenticate a socket record.
- WFP AppId is an opaque file-derived filter ID. Reparse points, hard links, mapped native paths, file replacement, executable signatures and publisher trust are NOT established by comparing strings.
- IPv6 mapped/link-local/scope/compartment behavior, DNS traffic from system components, UDP pseudo-flows and QUIC must be measured independently. TCP-only design asserts no UDP/QUIC interception.
- An owned synthetic ticket is a **proposed custom WFP redirect-context field**, not a Microsoft-defined connection-ID API. It must not be attached to old NDISRD packets by guesses.

## Pure Rust proof-contract prototype (no driver, network, or BFE calls)

`trust_contract.rs` is a dependency-free, `#![forbid(unsafe_code)]` Rust *decision model*, not interception code. It conditionally admits a selected TCP flow only if a single classified attempt and its accepted-socket receipt match on owner (PID + process creation epoch + exact opaque AppId), original endpoint, IP family, session, ticket, redirect state and record context; upstream must be ready. Replay is rejected using a bounded 4096-ticket set without eviction. There are **17 Rust unit tests** for benign/negative cases, including same 5-tuple with distinct tickets, same ticket reused, PID reuse, source substitution, wrong v4/v6 endpoint, missing context, other-provider loops, service loss and UDP/DNS limits.

`negative_cases.json` has **34 independent synthetic scenarios**. `independent_contract_audit.py` checks a separate Python specification oracle and a static no-Windows/no-driver Rust surface, using only stdlib. It does not claim that the Rust model and Python oracle were cross-language executed; both must eventually be compiled/run for agreement.

Offline commands:

~~~bash
python3 research/wfp-ale/independent_contract_audit.py
rustc --edition=2021 --test research/wfp-ale/trust_contract.rs -o /tmp/fb-wfp-trust-tests
/tmp/fb-wfp-trust-tests --nocapture
~~~

**This run:** Python specification/surface audit completed **34/34** with 2 conditional MODEL_ROUTE, 26 REJECT_INGRESS, 1 OUTSIDE_SCOPE, 3 UNCOVERED, 2 UNPROTECTED. No Rust compiler is installed in this isolated executor: **Rust compilation and 17 tests NOT RUN**. No Windows native runtime or external host was exercised.

## Next decisive, separately gated experiments

1. **No driver:** independently audit at which IRQL and lifecycle a referenced process + creation epoch can actually be captured for ALE_CONNECT_REDIRECT, and whether the kernel AppId and original address can be bound to that epoch. Read-only BFE inventory may be useful but does not replace this proof.
2. **Pure Rust compiler:** compile and execute all 17 unit tests, compare with the Python negative model, fix any discrepancies on this branch only.
3. **Authorization required first:** only after signed-driver, independent VNC/SYSTEM rescue, rollback, snapshot and owner gates, prove on a disposable Windows VM a **real** ALE redirect with accepted-socket context and WFP records across selected/nonselected same-name binaries, PID reuse and v4/v6.
4. Separately test the physical selected-app sibling DIRECT path during SSH loss and removal of WFP callout/filter, and observe UDP/DNS/QUIC and dual-stack leakage. Never report no-DIRECT from a user-mode-only denial.

## Microsoft primary sources (consulted 2026-11-07)

- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0

Strict research isolation: no ProxiFyre, closed PR #40, vendor binaries, reused C++ payload, driver activation, NDISRD, WFP filters, runner/system changes, network action, beta PR #56 edit, or historical G1 evidence promotion.
