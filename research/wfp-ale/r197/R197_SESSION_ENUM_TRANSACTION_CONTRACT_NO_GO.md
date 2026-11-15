# R197 — R190 cannot create a session enumerator inside FWPM_TXN_READ_ONLY

Date: 2026-11-15. Repository: i-shutov/flowbridge. Only branch research/windows-wfp-ale-attribution-20261107. Research parent ee5a8b33fe7c9dc04b9a662efe3ccc47c8d696e1 (R196), main 5b5afc2feeda2195f302380e615ba003d4906e09 (read-only).

## Source-level functional NO-GO, distinct from R196

Exact pre-patch Rust source r190/main.rs blob 775762e773ad2b2577d83a9976ef068df708f3e4 enters FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY), then inspect() calls session_count(), which invokes FwpmSessionCreateEnumHandle0 on the same engine inside that transaction. Microsoft documents that FwpmSessionCreateEnumHandle0 **cannot be called within an explicit transaction** and fails with FWP_E_TXN_IN_PROGRESS = 0x8032000E. Therefore, on the documented API contract, if engine open and transaction begin succeed, R190 fails at session_enum_create before reaching any filter inspection, irrespective of whether R19 dynamic objects are present. This is a concrete defect in the read-only diagnostic, **not** evidence of failed packet interception, R19 runtime failure, or DIRECT leakage. R187/src/main.rs inherited the same call order; it is historical source and is left unchanged.

The R196 independent precondition remains: absent active R19 dynamic-session objects, R190 cannot report STRUCTURE_OBSERVED_NOT_PROOF even with this diagnostic fixed. Additionally, BFE ACL can hide management objects. A positive inventory is only a management-object snapshot, never WFP kernel-origin/callback/packet proof.

## Minimal user-mode-only fix

In r190/main.rs, count visible BFE sessions and destroy that enumerator **before** FwpmTransactionBegin0. Pass the count as a separate snapshot into inspect(), and retain FwpmFilterCreateEnumHandle0/FwpmFilterEnum0 and four GetByKey validations inside the explicit read-only transaction. Microsoft specifically permits creating a filter enumeration handle inside a transaction for a current filter snapshot. Sessions and filters are now *not* one atomic snapshot: the count must not be joined to owner identity, transaction epoch, filter lifetime, or enforcement. No new BFE mutation API, driver, callout, filter, network socket or permission change was added. On failures, report UNKNOWN/NO_ATTESTATION.

## Independent negative evidence and limits

- Pre-patch and post-patch source call graph plus Microsoft API contract independently examined.
- Python R197 unittest includes old-order failure, new-order conditional allowance, and mutated-source guards; independent Node oracle includes 8 ordered-operation fixtures. Both predict FWP_E_TXN_IN_PROGRESS when session enumerator creation occurs with an explicit transaction active.
- Check actual full checkout with:
  python3 research/wfp-ale/r197/r197_txn_negative.py research/wfp-ale/r190/main.rs
  node research/wfp-ale/r197/r197_independent.mjs research/wfp-ale/r190/main.rs
- Synthetic deterministic cases and source-order checks are **not** execution of a Windows BFE API. No native Windows or Rust compilation is claimed. A filter enum handle in a read-only transaction is allowed by Microsoft; session enum creation is not.

## Primary Microsoft sources

- Session enumerator prohibition: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsessioncreateenumhandle0
- Filter enumerator transactional snapshot: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
- Transaction modes: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
- FWP_E_TXN_IN_PROGRESS numeric code: https://learn.microsoft.com/en-us/windows/win32/fwp/wfp-error-codes

## Current trust chain and next decisive experiment

Kernel referenced process/EPROCESS + PID/creation epoch/start key/canonical exe + opaque AppId -> real ALE_CONNECT_REDIRECT V4/V6 with source metadata and preserved original endpoint/compartment -> ALE_AUTH_CONNECT V4/V6 incl. reauthorize/sibling DIRECT -> WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) on actual accepted socket -> unique bounded ACK/CLAIM -> outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS -> proven SSH physical path.

Unproven: kernel-origin attribution, process death/PID reuse, reused 5-tuple, redirect-provider provenance, reauthorization, IPv4/IPv6, DNS/UDP/QUIC, competing filters, BFE/SSH loss and no-DIRECT. PacketBound/G2/G1 dd1ab3c acceptance not claimed. Next allowed experiment: compile exact modified R190 Rust for an admitted Windows 10 Pro x64 read-only user-mode host (after dependency lock/verification), log toolchain/OS/ABI/source/binary SHA, BFE status codes, and distinguish expected absent R19 dynamic objects from ACL/RPC failure. **No** driver/callout or policy activation without owner decision and all gates.

No main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, runners, automation, controller, paid operations, C++ WFP payload, vendor binaries, ProxiFyre AGPL or closed PR40 were touched.
