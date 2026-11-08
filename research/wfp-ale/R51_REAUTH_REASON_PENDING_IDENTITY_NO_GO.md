# R51 — AUTH_CONNECT reauthorization reason is documented; exact pending-operation binding remains NO-GO

2026-11-08. Independent research **only** on branch research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, PacketBound/G2, leak-free or historical G1 transfer. No native driver/callout/filter, runner, service, VNC, security-settings, network or automation mutation.

Pinned parent HEAD: 0ce4a8b70f8e9314efb8ee874cb2aff578eceff5; parent tree a8956e7b8090f614c87c93490c45e8333ed922a7; main 5b5afc2feeda2195f302380e615ba003d4906e09. Pinned source blobs: research/wfp-ale/kernel-r19/kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6; handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf; lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26.

## New documented evidence / correction to R49-R50

FWPS_FIELDS_ALE_AUTH_CONNECT_V4_ and V6_ explicitly expose REAUTHORIZE_REASON. FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION is documented separately from POLICY_CHANGE and other reasons. Therefore **cause discrimination is possible in principle** at this layer (GO only for existence of the API). It is not a kernel attestation of a specific process, ticket, pending operation, endpoint or flow. Missing, FWP_EMPTY or ambiguous reason cannot be guessed.

Current source auth_check unconditionally blocks IS_REAUTHORIZE before the one-shot Book::attest check and does not process the reason field. It has no FwpsPendOperation0 implementation. FwpsPendOperation0 takes the valid initial-AUTH completionHandle; FwpsCompleteOperation0 takes an opaque completionContext and returns void. Completion triggers a new reauthorization, not PERMIT. Microsoft explicitly requires separate unique pending-operation state so the later classify can retrieve the correct earlier decision; the reason flag alone cannot supply this link. Reauthorized connection fields may be FWP_EMPTY or classify an inbound packet at AUTH_CONNECT. No ownership/5-tuple correlation can substitute for native provenance.

## Executed negative tests (model evidence only)

- Python stdlib unittest: 17/17 PASS.
- Independent Node oracle published here is byte-for-byte the executed local source (Git blob 6f50e028660328129dc2e6021935fc809aa72f96).
- 30,720 synthetic states (2 families, 5 reasons, 3 phases, 10 assumed evidence guards): strict conditionally admitted 2; reason-only admitted 2048, of which **2046 are false admits relative to the strict model**.
- 10,080 synthetic event interleavings for two same-PID/same-5-tuple but distinct epoch/issuance/endpoint tickets: A permitted before observed exit in 420, B permitted in 1680; incorrect A receipt for B permitted in zero.
- 10 individual missing-guard negatives each fail the strict predicate; reason-only admits them.
- Standalone dependency-free Rust user-mode model: 23 unit tests WRITTEN, NOT COMPILED OR EXECUTED (rustc/cargo unavailable). Full Rust/Python/reports/logs are in the R51 checkpoint.
- This is not live Windows WFP proof, packet capture or physical forwarding.

## Trust boundary and next decisive experiment

Same native ALE_CONNECT_REDIRECT_V4/V6 event must bind original AppId, destination and PID to referenced process creation epoch/start key and canonical EXE. Kernel issues one-use ticket/session; initial AUTH_CONNECT_V4/V6 must authenticate it; pending completionHandle and completionContext must remain uniquely associated with that ticket through the completion-induced REAUTHORIZE_REASON=CLASSIFY_COMPLETION classify. The last link is **NOT PROVEN**. Then independently authenticate accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT, outbound SIO_SET records, and actual authenticated SSH handoff. Independently gate process death, PID/endpoint/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, v4/v6, WFP/SSH failure and physical egress.

R52: source-only verify field type, FWP_EMPTY and event-bound metadata on both sides of the pending completion; determine whether Microsoft documents an exact pending-operation identity visible on the new classify. If no proof, remain NO-GO. Do not run/install kernel code or change runner/network.

**Decision:** GO for existence of REAUTHORIZE_REASON and its CLASSIFY_COMPLETION category; NO-GO for exact ticket/owner binding, owner-liveness, restart/re-arm, sibling DIRECT, physical leak-free, PacketBound/G2 and historical G1 dd1ab3c transfer.

Official sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-flags-
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteoperation0
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
