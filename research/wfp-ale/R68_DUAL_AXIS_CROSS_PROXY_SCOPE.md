# R68 — Two-sided mismatch in current-AppId vs original-AppId WFP dispatch

**Date:** 2026-11-09. **Only:** `i-shutov/flowbridge`, branch `research/windows-wfp-ale-attribution-20261107`. Independent, offline architecture R&D. NOT beta, PR #56, G2/PacketBound, leak-free, native Windows acceptance, a driver change or filter activation.

## Source provenance / baseline

At the beginning of this cycle:

- Research HEAD: `bb9db1579a29e742d0de5d9f7ce36e74d9183db2` (R67).
- `main`: `5b5afc2feeda2195f302380e615ba003d4906e09`.
- `research/wfp-ale/kernel-r19/policy_windows.rs`: Git blob `acf60334320d970f58af3349ee75fbaa59826602`.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`.
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf`.
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs`: `0af6d4539673d2894cbaa91af0ea8f3524862a26`.

No production files modified. R68 adds a pure user-mode Rust guard, independently authored Python/Node offline negative oracles and research notes only.

## Actual source-level conflict and NEW reverse counterexample

`policy_windows.rs::conditions` uses `FWPM_CONDITION_ALE_APP_ID == selected` at `ALE_CONNECT_REDIRECT_V4/V6`, but `FWPM_CONDITION_ALE_ORIGINAL_APP_ID == selected` at `ALE_AUTH_CONNECT_V4/V6`; both also require TCP. Microsoft documents `ALE_ORIGINAL_APP_ID` as the initially originating application across proxy chains, potentially different from the *current* `ALE_APP_ID` on a proxied connection.

| Original | Current | Redirect condition | AUTH condition | Source-level consequence (conditional) |
|---|---|---|---|---|
| A | A | match | match | normal ticket and AUTH witness candidates only; NO native proof |
| A | B | miss | match | no own redirect issuance; if AUTH callback arrives, `auth_check` requests BLOCK rather than manufacture a ticket (R67) |
| C | A | match | miss | **NEW R68 reverse case**: `redirect::classify` checks current AppId and current endpoint-owner ledger, not original AppId. It can issue a ticket that the own AUTH selector cannot attest; `Book::take` then rejects un-attested CLAIM |
| C | C | miss | miss | outside these two selected-app filters; not a system PERMIT claim |

A is the selected EXE; B, C are other processes. The `C -> A` case arises if selected A *itself* is a proxy for unselected C. All issuing conditions (selected current process ledger, process epoch/start key, endpoint, origin destination, redirect state, health) are separately assumed to hold. The two-sided mismatch follows from exact filter conditions, not the claim that this path has been observed on native Windows.

The AUTH callback needs selected-original AppId and the same endpoint-origin ledger; merely switching the redirect selector to `ALE_ORIGINAL_APP_ID` is NOT a safe fix. If `Current=B, Original=A`, the WFP metadata `processId` describes the current endpoint owner B, not necessarily a referenced original EPROCESS of A. An old PID/tuple match cannot repair the trust boundary. Broadening both selectors to selected original can also pull B's proxy outbound leg into scope without proving the origin process.

## Primary Microsoft API boundary

- **`FWPS_METADATA_FIELD_PROCESS_ID`** is the PID of the *process owning the current endpoint*. Its process path counterpart likewise concerns that endpoint. It is not an automatically signed original-owner chain.
- **`FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`** identifies a transport endpoint; not an issuance epoch or ticket, and not a guarantee of identity across reconnects, endpoint death or PID reuse.
- **`FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID`** identifies the process targeted by redirect; not the original initiating process.
- **`FWPS_METADATA_FIELD_ORIGINAL_DESTINATION`** contains the original destination; not an owner certificate.
- **`FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE`** is available at CONNECT_REDIRECT for chain tracking; `FWPS_CONNECTION_REDIRECTED_BY_OTHER` needs independent interop decision, and `PREVIOUSLY_REDIRECTED_BY_SELF` must not be redirected again.
- **`FWPS_METADATA_FIELD_PROCESS_ID` and associated data must only be read when their presence bits are set.** The Microsoft layer metadata table and bind/connect redirection guidance do not in themselves establish unconditional availability of every field on every AUTH indication. Missing fields mean NO-GO, not a late PID+5-tuple correlation.
- **`PsSetCreateProcessNotifyRoutineEx` / referenced process identity** is still necessary to bind the owner at the original classify boundary, at permissible IRQL; it has NOT been shown to recover the historical process A from a proxy B endpoint.
- **`WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / ..._CONTEXT)`** attaches to the actual accepted socket, then `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` applies to an outbound proxy socket. These records do not supply the missing kernel original-owner witness or automatically authenticate the SSH channel.

Official documentation:

1. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
2. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
3. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers
4. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
5. https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
6. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
7. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
8. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0

## Executed deterministic tests

`python3 r68_cross_proxy_negative.py` — 17/17 PASS. Independent `node r68_independent_oracle.mjs` truth table. 131,072 states (IPv4+IPv6, TCP/UDP, 16 Boolean input bits). Python's set-of-guards decision engine and a separately authored bitwise Node algorithm agree on **every ordered result** and on the SHA-256 of the entire decision stream. A pair of mutation-sensitivity tests builds one-bit counterexamples against **12 issuance + 4 AUTH** independent guards, 16/16 detected.

Counts (conditional model, **not** Windows packets): 32 `ISSUE` candidates; 16 orphan-ticket candidates (current selected but original not selected); 8,192 observed AUTH-only (selected original/current foreign) with no own redirect; 16,382 `BLOCK_REQUESTED`; 2 model attestation candidates; 65,536 UDP/outside selected TCP condition cases. An unobserved callback is explicitly not a BLOCK, and BLOCK_REQUESTED is explicitly not a confirmed packet drop.

Pure Rust `r68_dual_axis_guard.rs`: `#![forbid(unsafe_code)]`, no extern/API/socket/driver, 16 unit tests written but **not compiled/executed** (no local `rustc/cargo`). Neither model performs Windows native classification or observes network traffic. A model attestation candidate is NEVER proof of G2 or leak-free egress.

## Decision / next decisive experiment (R69)

**GO only for source-level recognition of the symmetric dispatch mismatch and the exact negative contract.** Two possible collateral paths must be kept distinct: selected-original with foreign-current can trigger AUTH-only BLOCK_REQUESTED, while selected-current with foreign-original can create a ticket that cannot be authenticated by FlowBridge's own AUTH selector.

**NO-GO for a dual-axis filter rewrite now.** Proving the historical original EPROCESS, creation epoch, canonical EXE and exact ticket across layers with a foreign proxy requires evidence not provided by `ALE_ORIGINAL_APP_ID`, current endpoint `processId`, endpoint handle, redirect records or user-mode socket properties. Before changing runtime code, R69 should evaluate the WFP redirect-state matrix (`NOT_REDIRECTED`/`REDIRECTED_BY_SELF`/`REDIRECTED_BY_OTHER`/`PREVIOUSLY_REDIRECTED_BY_SELF`) for both axes, formalize a conservative foreign-proxy compatibility policy with distinct `UNOBSERVED`, `BLOCK_REQUESTED`, and `REJECTED_CLAIM`, and determine whether any documented native cross-inspector receipt can exist. Only offline code/tests/doc review is authorized.

Process death before callback, PID/endpoint and 5-tuple reuse, legitimate reauthorization, sibling DIRECT, DNS/UDP/QUIC, IPv4/v6 completeness, WFP/SSH loss and physical fail-closed remain NO-GO. Historical G1 evidence from dd1ab3c is not transferred. No main/release/beta, PR #56, driver, WFP filter, runner, service, firewall, UFW, Defender, SecureBoot, MemoryIntegrity, network, automation or other repository was touched.
