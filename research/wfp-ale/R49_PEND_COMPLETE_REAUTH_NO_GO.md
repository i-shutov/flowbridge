# R49 — AUTH_CONNECT PEND → COMPLETE → REAUTHORIZE: source-level NO-GO

2026-11-08. Only research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, G2/PacketBound, system no-DIRECT, or leak-free proof. No driver/callout/filter, CI, runner, services, network, signing, protections or automation changes.

## Verified inputs

Research base HEAD 934da7c40a20a287be66b66a475b8b60a9335e6c; tree 28e109c8c5f9488f44d2f715948c3aea7a08c626. Main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09. Pinned blobs: kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6, kernel/src/handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf, kernel/src/lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26 (under research/wfp-ale/kernel-r19).

Actual redirect::auth_check rejects IS_REAUTHORIZE (0x00000004), and auth_classify converts this failure to BLOCK. Book::attest is single-use and Book::take consumes the slot. No FwpsPendOperation0 state exists in this callback.

## API conflict

Microsoft documents FwpsPendOperation0 only for initial AUTH_CONNECT (and specified other ALE layers). The completion handle comes from FWPS_METADATA_FIELD_COMPLETION_HANDLE. FwpsCompleteOperation0 triggers a fresh AUTH_CONNECT reauthorization; it does not itself permit a flow. Pending an IS_REAUTHORIZE operation returns STATUS_FWP_CANNOT_PEND. Each pended initial classify needs unique state to locate its decision on reauthorization.

Ordinary policy-change or interface-triggered REAUTHORIZE may arrive on packets in either direction with FWP_EMPTY classifiable fields; it is not equivalent to completion of a known pending operation. Neither blanket PERMIT on REAUTHORIZE nor removal of just the flag check is acceptable.

Source-level result: simply inserting PEND/COMPLETE without a separately proven kernel-bound flow receipt creates a path to BLOCK, not a working async authorization. There is no documented automatic issuance ID from FwpsCompleteOperation0 to the existing Book.

## Executed negative experiment

Locally executed independent Python tests: 18 PASS and 1 SKIP (full checkout source-pin absent). Independent Node oracle in this commit agrees with Python over 65,536 synthetic Boolean cases; 4 conditional model authorizations and 14/14 missing-check mutants detected. Its successful cases ASSUME genuine kernel-origin and issuance-bound per-flow evidence, which has NOT been demonstrated by Windows. Current source model admits ZERO reauthorizations.

The detailed checkpoint contains the 23-test dependency-free pure Rust state machine (not compiled here), the full Python suite, Node oracle, results, logs, SHA256 manifest and expanded report. The remote commit publishes the independent executable oracle and this concise architecture report, not the uncompiled Rust or Python files.

## Trust boundaries and next decisive experiment

Must prove same kernel-origin process object/epoch/start key/canonical AppId at ALE_CONNECT_REDIRECT and AUTH_CONNECT (IPv4/V6); unique session and issuance-bound pending completion; separate established flow continuity under FWP_EMPTY; accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS; outbound SIO_SET records; broker-to-authenticated SSH; process-exit, PID/endpoint/5-tuple reuse; sibling DIRECT; DNS/UDP/QUIC and SSH/WFP loss. User-mode correlation cannot substitute for the native proof.

Next authorized step: execute the pure Rust model locally without runner or network; separately inspect official flow-context/metadata semantics read-only for a real native association across completion and policy reauthorization. If no proof exists under the current restrictions, stay NO-GO.

Primary docs:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

Kernel-origin issuance, owner liveness, safe REAUTHORIZE continuity, G2/PacketBound and leak-free remain NO-GO. Historical G1 dd1ab3c is not transferred.
