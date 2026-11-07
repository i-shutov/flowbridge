# R27 — stale AUTH after endpoint reuse: issuance provenance gap (conditional NO-GO)

Date: 2026-11-07. Independent architecture R&D only. Branch: research/windows-wfp-ale-attribution-20261107. No beta, PR #56, runner, filter, service, driver load/build/installation, security setting or automation change.

## Exact source and narrower finding

Read R26 at commit 472cbc739f9ba9f8108c5e352312769e8d7ddce5; source research/wfp-ale/kernel-r19/kernel/src/handoff.rs, Git blob f6200cac997f3c7e2fbd6a60443286727a8c2297.

Book::issue retires a live slot when now - issued > TTL (10 seconds). An endpoint duplicate is prohibited only while its earlier slot is live. Book::attest selects a live slot by (pid, creation epoch, start key, endpoint handle, owner generation, original destination), checks its timestamp, then marks auth_seen. There is NO match to the issuance sequence/context or an authentic event identifier obtained from the WFP AUTH classification. Book::take subsequently accepts the replacement context after auth_seen.

Thus, conditional on a late AUTH indication for issue A arriving after endpoint-handle reuse and issue B with the SAME visible origin/destination, AUTH(A) can mark B as authenticated. This is an offline identity-of-issuance ambiguity. It is not an observed Windows bypass: whether this interleaving is physically possible depends on WFP lifetime/ordering guarantees not established by the source or this test. Microsoft says a transport endpoint handle identifies an endpoint; its documentation does not in itself establish a forever-unique handle or a total order barring this interleaving.

## Exact negative witness

1. t=1: issue ticket A for selected executable identity X, endpoint E, original destination D (IPv4 or IPv6).
2. t=TTL+2: issue B for the same X/E/D; A is now expired and the book admits B.
3. t=TTL+3: old AUTH(A) is hypothetically delivered with X/E/D. Book::attest(X/E/D) marks the live B.
4. t=TTL+4: Book::take(context B) succeeds. An independent issuance-labelled oracle rejects AUTH(A) as authority for B.

Same PID+epoch+canonical AppId, same 5-tuple and WFP endpoint number do not distinguish A from B in this history. This is not a forged WFP metadata test. Reauthorization and process-death guards remain separate and are NOT proven by this witness.

## Test and independent check

Run: python3 research/wfp-ale/r27_auth_ticket_aba.py, optionally passing --source to fail closed unless the local file matches the pinned Git blob and required source predicates.

Performed offline: 16/16 conditional counterexample worlds (two families x eight targets); six independent control groups for no-AUTH rejection, same-ticket success, terminal claims, wrong endpoint, wrong destination; all assertions passed. The Python state projection is independent of the Rust execution. Separate GitHub read checked the exact Rust blob SHA and five decision snippets. The exact Rust code was NOT compiled/executed in this cycle; no Windows kernel event was observed.

## Trust boundary and next decisive safe experiment

AUTH_CONNECT metadata (FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE, PROCESS_ID, ORIGINAL_DESTINATION, LOCAL_REDIRECT_TARGET_PID and ORIGINAL_APP_ID) can attest WFP fields of an indication. Their value is not, by itself, a durable per-issuance secret. The private WFP redirect context and accepted-socket WSAIoctl records remain necessary for CLAIM, but the current Book::attest stage does not consume that context/receipt.

Safe next step: independent static review of whether Windows guarantees that late AUTH cannot be interleaved after endpoint recycling, using ALE_ENDPOINT_CLOSURE_V4/V6 and the documented endpoint-handle lifetime. If not established, design an issuance-bound kernel correlation that can be proved without timestamp/tuple heuristics, and extend the pure Rust user-mode Book tests. Do NOT create, load or modify a driver/callout or WFP filters under the current authorization.

Architectural status: kernel-origin issuance correlation = OPEN/NO-GO; G2/PacketBound and systemic no-DIRECT/leak-free = NO-GO; DNS/UDP/QUIC, IPv4/IPv6 physical coverage, sibling DIRECT, WFP/SSH loss require independent system gates.

Primary Microsoft sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers
