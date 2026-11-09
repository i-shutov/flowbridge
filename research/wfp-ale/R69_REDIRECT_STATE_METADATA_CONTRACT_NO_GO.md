# R69 — Two new documentation-contract blockers for ALE redirect/attestation

**Date:** 2026-11-09. **Repository:** i-shutov/flowbridge. **Only branch:** research/windows-wfp-ale-attribution-20261107. Independent, offline WFP/ALE R&D. Not beta, not PR #56, not G2, PacketBound or leak-free acceptance.

## Exact source baseline

Research HEAD at start: `e50858c4a1cce9c1244b695f9329a9982a1f4680`.
Main read-only HEAD: `5b5afc2feeda2195f302380e615ba003d4906e09`.

The relevant existing (unchanged) Git blobs:
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` — `9a07e026134d46ef646d39862bd982cc48bbc5f6`
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs` — `0af6d4539673d2894cbaa91af0ea8f3524862a26`
- `research/wfp-ale/kernel-r19/policy_windows.rs` — `acf60334320d970f58af3349ee75fbaa59826602`
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs` — `e1d17217db50362ba9c4efc83af820b6beb094cf`

The source inspection was repeated against the Git blobs, not inferred from old reports.

## Finding 1 — unqueried redirect state can reach Book::issue

`redirect::classify()` checks `FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE` only in an `if` statement. Inside it, `FwpsQueryConnectionRedirectState0(m.redirectRecords, HANDLE, NULL)` selects the four documented states. **If the presence bit is absent, there is no else/fail guard:** the code continues to writable CONNECT_REDIRECT handling and, if other existing identity/health guards succeed, `Book::issue()`.

Microsoft's Windows 8+ connect-redirection instructions explicitly say the redirect state **must be queried** to prevent endless proxy loops. The layer metadata inventory lists redirect-record handle as *possible*, not unconditionally available. Neither its absence nor a null handle is documented as equivalent to `FWPS_CONNECTION_NOT_REDIRECTED`. This is a source-level **unverified-state-to-issuance path**. It is **not** a reproduced Windows leak, and a scenario with missing metadata and an actually previously redirected flow is a *hypothetical observational counterexample*, not proved natively reachable.

Source behavior with record metadata present:

| WFP state | Source-level requested behavior | Microsoft guidance |
|---|---|---|
| NOT_REDIRECTED | may issue with additional guards | may redirect |
| REDIRECTED_BY_SELF | return/outer CONTINUE, no new issue | permit/continue |
| REDIRECTED_BY_OTHER | request BLOCK, no new issue | may reproxy if inspector untrusted |
| PREVIOUSLY_REDIRECTED_BY_SELF | return/outer CONTINUE, no new issue | **must not** re-redirect; permit/block belongs to AUTH_CONNECT |
| Unknown / MAX | request BLOCK | not a valid state |
| Record metadata absent | **query skipped; issuance candidate** | no implication that state is clean |

For SELF/PREV_SELF the early return occurs before the source's lease/SSH check `ready(now())`. That is another unproved cross-layer-health boundary, **not** a claim that packets physically pass. A null records handle with presence bit set is not modeled as a successful query; native API behavior is unspecified in this review.

## Finding 2 — mandatory AUTH metadata has no published layer support

`redirect::auth_check()` requires the following four `currentMetadataValues` bits at **ALE_AUTH_CONNECT_V4/V6**:
- `FWPS_METADATA_FIELD_PROCESS_ID`
- `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`
- `FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID`
- `FWPS_METADATA_FIELD_ORIGINAL_DESTINATION`

Microsoft's published **Metadata fields at each filtering layer** table includes the first two for AUTH_CONNECT, but **does not include LOCAL_REDIRECT_TARGET_PID or ORIGINAL_DESTINATION** in that layer's set of possible fields. `LOCAL_REDIRECT_TARGET_PID` is listed at CONNECT_REDIRECT; `originalDestination` is a member of `FWPS_INCOMING_METADATA_VALUES0`, but its presence at AUTH_CONNECT is **not established** by the layer inventory. Thus the present R19 AUTH receipt lacks a documented path to satisfying its mandatory mask, on both IP families. Under the published inventory `auth_check` will fail. This is a **documentation-contract NO-GO**, not an absolute claim that every Windows build always omits the fields.

The same struct's `processId` denotes the **current endpoint owner**, not a kernel attestation of an earlier original process through an unrelated proxy. Even if the missing fields turn out to be supplied in practice, PID+epoch+canonical EXE and one-use ticket still require proof of their exact origin/endpoint binding and no sibling DIRECT.

## Executable negative tests and independent check

- `r69_published_negative.py`: **10/10 PASS** on Python 3.13, covers absent records, four states plus MAX, null records, self return before health, both AppId mismatch directions, missing AUTH callback, documented metadata inventory, physically dead owner and TCP-only scope.
- `r69_published_independent.mjs`: separately implemented Node 22 bitmask oracle. **2,560 synthetic states** (IPv4/IPv6, five states, 256 masks), **exactly matching** all Python counters and ordered-stream SHA-256 `d8e372a234ea32401adcd4ee02ffb2baefd675c1d58e3184dc1aec939697fafc`.
- In the 2,560-state model, **160** issue candidates arise with no redirect-state query; **96** of these were artificially assigned nonclean hidden state. **32** SELF/PREV_CONTINUE states occur with failed combined health guard. These counts are *model behavior*, not WFP reachability or physical packet counts.
- Extended local checkpoint contains **20/20** Python tests and an independent Node oracle over **163,840** synthetic states (SHA-256 `cf96c7e41acf1733bdd78a8a20799d6d653923eb5eea6c26c1da0b1e3d0965bd`), plus independent 6/6 metadata-contract tests and pure Rust user-mode offline guard with 19 authored tests. Rust **not compiled**; no compiler available. Native WFP calls/packets: **zero**.

## Official Microsoft documentation (reviewed 2026-11-09)

1. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
2. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
3. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
4. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
5. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_connection_redirect_state_
6. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking

## Trust boundary and decision

**NO-GO** for declaring WFP/ALE kernel-origin attribution, reliable `ISSUE -> AUTH_CONNECT -> CLAIM` or compatibility with multi-proxy chains. A record handle is chain tracking, not an original-owner certificate. BFE filter match is not cross-layer identity. A selected callback requesting BLOCK is not a physical packet-drop receipt; missing callback means UNOBSERVED, not BLOCK or PASS. 5-tuple reuse, PID reuse/death, owner start epoch and canonical EXE, IPv4/IPv6, sibling DIRECT, DNS/UDP/QUIC and WFP/SSH loss still lack end-to-end proof. No historical G1 transfer.

**R70 next decisive experiment:** inspect official WDK/SDK metadata contracts for AUTH_CONNECT, find a documented alternative for `originalDestination` and `localRedirectTargetPID` or close the existing AUTH ticket protocol as design NO-GO; independently establish when `redirectRecords` metadata can be absent and whether it is valid to query a clean connection. Only compiler-only/offline checks, no kernel driver/callout, WFP filters, BFE mutation, network, VNC or host changes.

Main/release, beta integration branch, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories and automations were not touched.
