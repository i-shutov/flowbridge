# R70 — Correction of R69: AUTH_CONNECT metadata documentation conflict

2026-11-09. Scope: i-shutov/flowbridge, solely research/windows-wfp-ale-attribution-20261107. Independent architecture R&D; NOT beta, PR #56, G2/PacketBound, leak-free or historic G1 acceptance.

**Pinned source HEAD:** research b9e58ed285d620073a85ea12936fbb1d013b665c, main 5b5afc2feeda2195f302380e615ba003d4906e09 (read-only). R19 Rust source blobs, unmodified: redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6; handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf; policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602.

## Critical correction to R69

The general Microsoft Metadata fields at each filtering layer inventory (updated **2021-12-15**) omits FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID and FWPS_METADATA_FIELD_ORIGINAL_DESTINATION from its ALE_AUTH_CONNECT_V4/V6 rows. But Microsoft Using Bind or Connect Redirection (**2024-09-27**), in its multiple callouts section, **explicitly directs connect-redirection callouts to check BOTH those fields at ALE_AUTH_CONNECT_V4/V6** when FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED is set.

These two official publications contradict one another. The direct scenario-specific guidance establishes a documented *conditional* AUTH metadata path; R69's categorical claim that no such documented path exists was therefore **incorrect**. Neither document guarantees any particular Windows build provides the metadata every time. Check currentMetadataValues on each actual callback; absence must fail closed. Metadata field identifiers and FWPS_INCOMING_METADATA_VALUES0 independently document the bit names and fields.

The procedure's later spelling LOCAL_REDIRECT_TARGET_ID rather than LOCAL_REDIRECT_TARGET_PID appears to be an editorial inconsistency, not evidence of a second published field: the bullet list and metadata identifier page use PID.

**Narrow GO:** retain R19's four-bit AUTH presence mask, since the official procedure supports the redirect-specific bits under its scenario. Do NOT remove the guard or assert native success. R19 still has no validated real Windows callback test.

## Chain of trust: remaining gaps

PROCESS_ID refers to the *current endpoint owner*; TRANSPORT_ENDPOINT_HANDLE is the current transport endpoint. LOCAL_REDIRECT_TARGET_PID is the process responsible for a redirected flow, ORIGINAL_DESTINATION is its original destination. These do not independently prove the originating EPROCESS across foreign proxies, retained process creation epoch/start key+canonical EXE, causal matching of CONNECT_REDIRECT and AUTH_CONNECT or accepted-socket-to-CLAIM binding.

R19 additionally requires selected ALE_ORIGINAL_APP_ID, redirected flag, TCP, loopback broker and port, matching broker PID, process ledger epoch/start key/EXE, endpoint, destination, health lease, and one-use ticket. Good checks are not a historical-owner certificate. AppId/PID/5-tuple correlations and identical EXE paths are insufficient under PID reuse, process death and proxied chains.

## Separate persistent NO-GO: unqueried redirect state

R19 redirect::classify() tests presence of FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE and only then calls FwpsQueryConnectionRedirectState0. If absent, it can reach Book::issue after other guards. Microsoft says Windows 8+ redirect callouts MUST query state before performing redirect. Neither missing metadata nor a null records handle is documented to mean FWPS_CONNECTION_NOT_REDIRECTED. This is a source-level unqueried-state-to-issuance candidate, NOT proof of a reachable Windows foreign-proxy exploit or physical packet leak. BY_SELF and PREVIOUSLY_BY_SELF must never be re-redirected; BY_OTHER still needs independent inspector trust decision.

## Executable negative experiment, pure offline

r70_auth_predicate.py, Python 3.13: **14/14 unit tests PASS**.
r70_independent_oracle.mjs: independent Node Boolean evaluator, matching Python on **131,072 synthetic AUTH states** and **512 synthetic redirect states**, across IPv4 and IPv6.

AUTH decision-stream SHA256 **2ec9a6d8adf2721a2a66263591be24b244648497d68b754d3ab1f47e7d3a15d0**; 8 synthetic CONDITIONAL_RECEIPT states. Four have observationally identical counterparts with a different hidden historical owner, and four with hidden sibling DIRECT. A conditional classification is NOT proof of actual native auth or kernel-origin identity.

Redirect stream SHA256 **95be917a3e147a27e436e65f7ed8e88347998c1b138a13ce1733d9bb6dd2e713**: 8 model issuance candidates with missing redirect-state query, including 4 with hypothetically hidden foreign redirect. These are **model** counterexamples, not observed Windows flows or drops. Pure Rust offline r70_guard.rs contains 22 authored tests, not executed (rustc/cargo unavailable); no unsafe, FFI or driver calls.

## GO/NO-GO and next R71

GO only for correcting the R69 overstatement; document/retain the four-bit conditional AUTH guard. NO-GO persists for original process PID+epoch+canonical EXE provenance, secure one-use redirect-to-CLAIM socket join, IPv4/IPv6 packet egress, owner liveness, PID and 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH loss, PacketBound/G2 and leak-free.

**R71 decisive:** offline source-driven proof of query-before-issue across redirect record absent/null, NOT_REDIRECTED, BY_SELF, BY_OTHER, PREVIOUSLY_BY_SELF, both AppId axes, IPv4 and IPv6. If no official way to query without redirect records is established, missing metadata is UNVERIFIED and remains NO-GO, never implicitly clean. All tests require no driver or network.

## Microsoft sources (verified 2026-11-09)

- Specific procedure, 2024-09-27: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- General inventory, 2021-12-15: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- Identifiers: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers
- Structure: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- Query state: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0

No main/release, integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories or automations touched.
