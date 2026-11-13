# FlowBridge WFP/ALE R152 — hypothetical endpoint ABA / stale AUTH indistinguishability

Date: 2026-11-13. Strictly branch research/windows-wfp-ale-attribution-20261107. Development base research HEAD 007c7e82492a0411900e4cf77ab673e545bcc6cb; main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09. Research-only. Architecture NO-GO.

## Significant conditional finding

R151 showed that the R150 selected-only Candidate accepts two one-shot claims for the same endpoint. R152 tests the tempting fix for R19's 4096 immutable endpoint tombstones: deleting a tombstone at ALE_ENDPOINT_CLOSURE. **That fix is not justified by the currently available evidence.**

Assume that Windows later reuses the same numeric transport endpoint handle, and that an old ALE_AUTH_CONNECT classify can be delivered after closure and after a new issuance. These are **explicitly hypothetical** assumptions, NOT witnessed Windows behavior. When the process PID, creation epoch/start key, opaque original AppId, address family, compartment and original destination are identical, a delayed AUTH event from the old issuance is observationally identical to the genuine AUTH for the new issuance. A policy that permits the new event based only on those fields would also misattribute the old event. The user's application ticket/sequence is not present in the documented WFP AUTH observation.

Source R19 has Book::attest matching process Origin fields and destination, but no endpoint-issuance sequence in its AUTH inputs. Its generation is the *process ledger* generation, not an endpoint generation. The Context has no compartment field. Actual R19 prevents same numeric endpoint reissue using permanent session tombstones; the risk occurs only if that protection is weakened without a proved lifetime protocol.

This is an **information boundary**, not an assertion that Windows leaks or necessarily reuses a handle. Microsoft's ALE Endpoint Lifetime Management documentation says each endpoint receives a unique handle and defines endpoint closure. It does not promise that numeric handles never recycle throughout arbitrary future sessions or that proxy CLAIMs/delayed WFP AUTH work drain before application tombstones are freed.

## Executable negative results

The Python implementation reads and verifies the exact R150 and R151 source Git blobs before running. It uses no OS/network/WFP operations. An independently implemented Node.js oracle produces the same 128-row matrix. Python 3.13.5 normal, -O and -OO plus Node.js 22.16.0 all passed 128/128.

- 128 synthetic cases: two families x same/different process epoch, AppId, compartment, original destination, numeric endpoint handle, and delayed/normal AUTH.
- 2 delayed AUTH cases are indistinguishable even with a stronger-than-R19 visible tuple.
- 4 delayed AUTH cases match a weaker R19 Book-shaped predicate, including hypothetical compartment differences.
- 64 fresh AUTH cases pass the naive closure-only model.
- Session quarantine denies same-numeric-handle reissuance; this protects the modeled ambiguity but sacrifices availability.
- A hypothetical native per-issuance nonce distinguishes the traces, but no such Windows API is claimed.
- R150 and R151 blobs were validated locally (2/2). R19 handoff.rs and redirect.rs were independently inspected and blob-pinned using GitHub; full local R19 pin execution was NOT performed.
- An intentionally modified pinned source was rejected under Python -O.

Matrix SHA-256: 7a93d41d8ce5a37056d269415e9f5a9aa1d746c34c80f1440814986474ef81c4.

Commands (repository root):

    python -B research/wfp-ale/r152/r152_aba_negative.py --r19-root research/wfp-ale/kernel-r19
    python -O -B research/wfp-ale/r152/r152_aba_negative.py --r19-root research/wfp-ale/kernel-r19
    python -OO -B research/wfp-ale/r152/r152_aba_negative.py --r19-root research/wfp-ale/kernel-r19
    node research/wfp-ale/r152/r152_independent.mjs

On a partial checkout, omit --r19-root; the output explicitly marks local R19 source pins unverified. The independent scripts contain no kernel payload or native acceptance claims.

## Exact source references and Windows APIs

- R19 handoff.rs Git blob e1d17217db50362ba9c4efc83af820b6beb094cf; R19 redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09. Neither modified.
- Microsoft ALE Endpoint Lifetime Management: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- Microsoft Metadata fields by layer: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- Microsoft ALE_CONNECT_REDIRECT V4 and ALE_AUTH_CONNECT V4 fields, including COMPARTMENT_ID (Windows 10 1703+):
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- Relevant future native observations are FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE, FWPS_METADATA_FIELD_PROCESS_ID, FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6, FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6, FwpsPendClassify0 and FwpsCompleteClassify0. Presence must be checked, not assumed.
- WFP redirect context/records are only meaningful on the actual accepted socket through WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS); proxy outbound socket uses SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before connect.

## Trust boundary / decisive experiment

A decisive *future authorized* native lab would record the causal sequence of one kernel-referenced process (PID, creation epoch, start key and exact AppId), CONNECT_REDIRECT issuance and endpoint handle, AUTH/reauthorization classification, closure/pending completion, and the same accepted socket's WFP records, one-shot claim and physical SSH transfer. It must intentionally check endpoint-reuse and delayed AUTH ordering, process death/PID reuse, reused 5-tuple, IPv4/v6 compartments, sibling DIRECT, DNS/UDP/QUIC and BFE/SSH loss. Without proof of a trusted issuance identity shared across classify phases, or a native quiescence guarantee, safe tombstone reclamation is NO-GO.

No kernel driver, callout, NDISRD, WFP filter, system setting, network, runner, automation, main, release, beta or PR #56 was touched. Native Windows and Rust compilation NOT RUN. This research does not claim PacketBound/G2 PASS, no-DIRECT, leak-free or historical G1 acceptance.
