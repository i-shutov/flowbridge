# R208 — endpoint closure missing from R19 terminal-CLAIM evidence

2026-11-16. Only research/windows-wfp-ale-attribution-20261107. Parent 5a682a619697f4c46951c8e390634080855ed642, observed main 5b5afc2feeda2195f302380e615ba003d4906e09. Independent architecture R&D, not beta/PR #56/G2.

## Source-level counterexample (conditional, NOT observed Windows ordering)

R19 registers exactly four kernel callouts: ALE CONNECT_REDIRECT V4/V6 and AUTH_CONNECT V4/V6. policy_windows.rs installs only those four filter kinds. There is **no** ALE_ENDPOINT_CLOSURE_V4/V6 callout/filter and no endpoint-closure retirement in handoff.rs::Book. Thus the Book state trace ISSUE(ep,A) -> valid AUTH(ep,A) -> original TCP ENDPOINT_CLOSURE(ep,A) while owner process remains live -> terminal CLAIM(ep,A) within TTL is still admissible by Book.take. A closure-aware model denies the claim. IPv4 and IPv6 reproduce the same gap.

This is a *distinct* lifetime gap from R207 (reauthorization). No real endpoint closure callback was invoked. Windows might tear down the accepted socket before CLAIM, and source-level admission is not an observed DIRECT leak, packet egress, or native kernel proof.

## Pinned Git blobs (freshly re-fetched with independent structure checks)

- kernel-r19/kernel/src/lib.rs: 53f5ce6faa0f9f591974287f38ea890cafeb0dd2
- kernel-r19/kernel/src/redirect.rs: a093f049d162987981a957aac90db1014bc6ff09
- kernel-r19/kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf
- kernel-r19/policy_windows.rs: acf60334320d970f58af3349ee75fbaa59826602

Official Microsoft docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer . Per documentation, FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6 can report TCP close with FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE. A future exact same-endpoint closure-veto is a separate design hypothesis, not authorized driver work. PID/5-tuple correlation alone is insufficient.

## Tests and limits

Run: python research/wfp-ale/r205/r208_closed_endpoint_test.py (6/6 PASS); node research/wfp-ale/r205/r208_closed_endpoint_oracle.mjs (10/10 PASS). An offline expanded checkpoint independently ran Python 10/10 and Node 15/15 additional negative traces; GitHub source audit 4/4 exact blob SHAs and 15 structural guards PASS. A PASS means reproducing a *bad admission* in synthetic state, not a verified Windows security property. No Rust toolchain, BFE, Windows classify or driver executed. The committed compact scripts and offline expanded tests are distinct files; both test the same invariant.

Trust chain still NO-GO: birth-time referenced EPROCESS/FileObject + PID/epoch/start key/canonical EXE -> ALE REDIRECT V4/V6 -> AUTH_CONNECT V4/V6 -> lifecycle reauthorization/closure -> accepted-socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) -> terminal claim -> outbound physical SSH SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS. Not proven. Sibling DIRECT, DNS/UDP/QUIC, process reuse, repeated 5-tuple, dual-stack, lost WFP/SSH and missing filters remain open. PacketBound/G2, no-DIRECT, leak-free and historical G1 inheritance are NOT claimed.

Next permitted experiment: native R201/R202 standalone read-only user-mode Rust, optional passive R199 BFE readback on approved Windows 10 Pro. Any kernel endpoint-close classify experiment requires separate owner decision and full driver/VNC/SYSTEM rescue/rollback gates. No restricted system or ref changes except this research-branch update.
